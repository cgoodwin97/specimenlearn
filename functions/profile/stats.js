import { corsHeaders, getSessionToken, handleOptions } from '../_auth_utils.js';

export async function onRequestOptions() {
  return handleOptions();
}

export async function onRequestGet({ request, env }) {
  const token = getSessionToken(request);
  if (!token) return unauth();

  const session = await env.SPECIMEN_DB.prepare(
    `SELECT s.expires_at, u.id as user_id
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ?`
  ).bind(token).first();

  if (!session || new Date(session.expires_at) < new Date()) return unauth();

  // All completed lessons, most recent first
  const { results } = await env.SPECIMEN_DB.prepare(
    `SELECT course, unit, lesson, completed_at
     FROM lesson_progress
     WHERE user_id = ? AND status = 'complete'
     ORDER BY completed_at DESC`
  ).bind(session.user_id).all();

  const rows = results || [];
  const totalLessons = rows.length;

  // Per-course breakdown
  const byCourse = {};
  for (const row of rows) {
    byCourse[row.course] = (byCourse[row.course] || 0) + 1;
  }

  // Streak calculation: distinct calendar days with at least one completion,
  // counting back consecutively from today (or yesterday, if nothing done today yet)
  const dateSet = new Set(
    rows
      .filter(r => r.completed_at)
      .map(r => r.completed_at.slice(0, 10)) // YYYY-MM-DD
  );

  function fmt(d) { return d.toISOString().slice(0, 10); }

  let streak = 0;
  let cursor = new Date();
  const todayStr = fmt(cursor);

  // If nothing completed today, start checking from yesterday instead
  // (keeps the streak alive through the current day until it actually lapses)
  if (!dateSet.has(todayStr)) {
    cursor.setDate(cursor.getDate() - 1);
  }

  while (dateSet.has(fmt(cursor))) {
    streak++;
    cursor.setDate(cursor.getDate() - 1);
  }

  return new Response(JSON.stringify({
    ok: true,
    total_lessons: totalLessons,
    by_course: byCourse,
    streak,
    last_completed: rows.length ? rows[0].completed_at : null,
  }), { status: 200, headers: corsHeaders('application/json') });
}

function unauth() {
  return new Response(JSON.stringify({ ok: false, error: 'Not signed in.' }), {
    status: 401, headers: corsHeaders('application/json'),
  });
}
