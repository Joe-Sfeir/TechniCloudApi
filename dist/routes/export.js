"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const exceljs_1 = __importDefault(require("exceljs"));
const date_fns_1 = require("date-fns");
const db_1 = require("../db");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
router.use(auth_1.requireAuth);
// ── GET /api/export/:projectId ────────────────────────────────────────────────
router.get('/:projectId', async (req, res) => {
    const projectId = Number(req.params['projectId']);
    if (!Number.isInteger(projectId) || projectId <= 0) {
        res.status(400).json({ error: 'projectId must be a positive integer.' });
        return;
    }
    const userId = res.locals['userId'];
    const role = res.locals['role'];
    // Fetch project — MASTER/SUB_MASTER can export any; CLIENT only their own
    const projectResult = await db_1.pool.query('SELECT id, name, user_id FROM projects WHERE id = $1', [projectId]);
    const project = projectResult.rows[0];
    if (!project) {
        res.status(404).json({ error: 'Project not found.' });
        return;
    }
    if (role === 'CLIENT' && project.user_id !== userId) {
        res.status(403).json({ error: 'Forbidden.' });
        return;
    }
    // Fetch all telemetry ordered for sheet grouping
    const telemetryResult = await db_1.pool.query(`SELECT device_name, timestamp, data
     FROM telemetry
     WHERE project_id = $1
     ORDER BY device_name ASC, timestamp ASC`, [projectId]);
    if (telemetryResult.rows.length === 0) {
        res.status(404).json({ error: 'No telemetry data found for this project.' });
        return;
    }
    // Group rows by device_name
    const deviceMap = new Map();
    for (const row of telemetryResult.rows) {
        const existing = deviceMap.get(row.device_name);
        if (existing) {
            existing.push(row);
        }
        else {
            deviceMap.set(row.device_name, [row]);
        }
    }
    const workbook = new exceljs_1.default.Workbook();
    workbook.creator = 'TechniDAQ Cloud';
    workbook.created = new Date();
    const exportDate = (0, date_fns_1.format)(new Date(), 'yyyy-MM-dd HH:mm:ss');
    for (const [deviceName, rows] of deviceMap) {
        const worksheet = workbook.addWorksheet(deviceName.slice(0, 31)); // Excel sheet name max 31 chars
        // ── Corporate Header (Rows 1–5) ───────────────────────────────────────────
        const firstRow = rows[0];
        const dataKeys = firstRow ? Object.keys(firstRow.data) : [];
        const totalCols = Math.max(dataKeys.length + 1, 4); // +1 for Timestamp column
        const addHeaderRow = (label, value) => {
            const row = worksheet.addRow([label, value]);
            const labelCell = row.getCell(1);
            const valueCell = row.getCell(2);
            labelCell.font = { bold: true };
            valueCell.font = { bold: false };
            worksheet.mergeCells(row.number, 2, row.number, totalCols);
        };
        addHeaderRow('Company', 'TechniCAT Group');
        addHeaderRow('Project', project.name);
        addHeaderRow('Device', deviceName);
        addHeaderRow('Exported', exportDate);
        worksheet.addRow([]); // Row 5 — empty separator
        // ── Column Headers (Row 6) ────────────────────────────────────────────────
        const headerRow = worksheet.addRow(['Timestamp', ...dataKeys]);
        headerRow.eachCell((cell) => {
            cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F4E79' } };
            cell.alignment = { horizontal: 'center' };
            cell.border = {
                bottom: { style: 'thin', color: { argb: 'FFFFFFFF' } },
            };
        });
        // Set column widths
        worksheet.getColumn(1).width = 22; // Timestamp
        dataKeys.forEach((_key, i) => { worksheet.getColumn(i + 2).width = 18; });
        // ── Data Rows (Row 7+) ────────────────────────────────────────────────────
        for (const row of rows) {
            const formattedTimestamp = (0, date_fns_1.format)(new Date(row.timestamp), 'yyyy-MM-dd HH:mm:ss');
            const dataValues = dataKeys.map((key) => {
                const val = row.data[key];
                return val !== null && val !== undefined ? String(val) : '';
            });
            worksheet.addRow([formattedTimestamp, ...dataValues]);
        }
        // ── Sheet Protection ──────────────────────────────────────────────────────
        await worksheet.protect('TDAQ_Secure_2026!', {
            selectLockedCells: true,
            selectUnlockedCells: true,
        });
    }
    // ── Stream response ───────────────────────────────────────────────────────
    const filename = `TDAQ_Project${projectId}_${(0, date_fns_1.format)(new Date(), 'yyyy-MM-dd')}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    await workbook.xlsx.write(res);
    res.end();
});
exports.default = router;
//# sourceMappingURL=export.js.map