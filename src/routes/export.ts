import { Router } from 'express';
import type { Request, Response } from 'express';
import ExcelJS from 'exceljs';
import { format } from 'date-fns';
import { pool } from '../db';
import { requireAuth, requireRole } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

// ── GET /api/export/:projectId ────────────────────────────────────────────────

router.get('/:projectId', async (req: Request, res: Response): Promise<void> => {
  const projectId = Number(req.params['projectId']);
  if (!Number.isInteger(projectId) || projectId <= 0) {
    res.status(400).json({ error: 'projectId must be a positive integer.' });
    return;
  }

  const userId = res.locals['userId'] as number;
  const role   = res.locals['role']   as string;

  // Fetch project — MASTER/SUB_MASTER can export any; CLIENT only assigned projects
  const projectResult = await pool.query<{ id: number; name: string }>(
    'SELECT id, name FROM projects WHERE id = $1',
    [projectId],
  );

  const project = projectResult.rows[0];
  if (!project) {
    res.status(404).json({ error: 'Project not found.' });
    return;
  }

  if (role === 'CLIENT') {
    const assignment = await pool.query(
      'SELECT 1 FROM project_assignments WHERE project_id = $1 AND user_id = $2',
      [projectId, userId],
    );
    if ((assignment.rowCount ?? 0) === 0) {
      res.status(403).json({ error: 'Forbidden.' });
      return;
    }
  }

  // Fetch all telemetry ordered for sheet grouping
  const telemetryResult = await pool.query<{
    device_name: string;
    timestamp: Date;
    data: Record<string, unknown>;
  }>(
    `SELECT device_name, timestamp, data
     FROM telemetry
     WHERE project_id = $1
     ORDER BY device_name ASC, timestamp ASC`,
    [projectId],
  );

  if (telemetryResult.rows.length === 0) {
    res.status(404).json({ error: 'No telemetry data found for this project.' });
    return;
  }

  // Group rows by device_name
  const deviceMap = new Map<string, typeof telemetryResult.rows>();
  for (const row of telemetryResult.rows) {
    const existing = deviceMap.get(row.device_name);
    if (existing) {
      existing.push(row);
    } else {
      deviceMap.set(row.device_name, [row]);
    }
  }

  const workbook = new ExcelJS.Workbook();
  workbook.creator  = 'TechniDAQ Cloud';
  workbook.created  = new Date();
  const exportDate  = format(new Date(), 'yyyy-MM-dd HH:mm:ss');

  for (const [deviceName, rows] of deviceMap) {
    const worksheet = workbook.addWorksheet(deviceName.slice(0, 31)); // Excel sheet name max 31 chars

    // ── Corporate Header (Rows 1–5) ───────────────────────────────────────────
    const firstRow = rows[0];
    const dataKeys = firstRow ? Object.keys(firstRow.data) : [];
    const totalCols = Math.max(dataKeys.length + 1, 4); // +1 for Timestamp column

    const addHeaderRow = (label: string, value: string) => {
      const row = worksheet.addRow([label, value]);
      const labelCell = row.getCell(1);
      const valueCell = row.getCell(2);
      labelCell.font = { bold: true };
      valueCell.font = { bold: false };
      worksheet.mergeCells(row.number, 2, row.number, totalCols);
    };

    addHeaderRow('Company',     'TechniCAT Group');
    addHeaderRow('Project',     project.name);
    addHeaderRow('Device',      deviceName);
    addHeaderRow('Exported',    exportDate);
    worksheet.addRow([]); // Row 5 — empty separator

    // ── Column Headers (Row 6) ────────────────────────────────────────────────
    const headerRow = worksheet.addRow(['Timestamp', ...dataKeys]);
    headerRow.eachCell((cell) => {
      cell.font      = { bold: true, color: { argb: 'FFFFFFFF' } };
      cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F4E79' } };
      cell.alignment = { horizontal: 'center' };
      cell.border    = {
        bottom: { style: 'thin', color: { argb: 'FFFFFFFF' } },
      };
    });

    // Set column widths
    worksheet.getColumn(1).width = 22; // Timestamp
    dataKeys.forEach((_key, i) => { worksheet.getColumn(i + 2).width = 18; });

    // ── Data Rows (Row 7+) ────────────────────────────────────────────────────
    for (const row of rows) {
      const formattedTimestamp = format(new Date(row.timestamp), 'yyyy-MM-dd HH:mm:ss');
      const dataValues = dataKeys.map((key) => {
        const val = row.data[key];
        return val !== null && val !== undefined ? String(val) : '';
      });
      worksheet.addRow([formattedTimestamp, ...dataValues]);
    }

    // ── Sheet Protection ──────────────────────────────────────────────────────
    await worksheet.protect('TDAQ_Secure_2026!', {
      selectLockedCells:   true,
      selectUnlockedCells: true,
    });
  }

  // ── Stream response ───────────────────────────────────────────────────────
  const filename = `TDAQ_Project${projectId}_${format(new Date(), 'yyyy-MM-dd')}.xlsx`;
  res.setHeader('Content-Type',        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  await workbook.xlsx.write(res);
  res.end();
});

export default router;
