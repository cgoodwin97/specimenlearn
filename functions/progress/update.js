import { corsHeaders, getSessionToken, handleOptions } from '../_auth_utils.js';

export async function onRequestOptions() {
  return handleOptions();
}

export async function onRequestPost({ request, env }) {
  const token = getSessionToken(request);
  if (!token) return unauth();

  const session = await env.SPECIMEN_DB.prepare(
    `SELECT s.expires_at, u.id as user_id
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ?`
  ).bind(token).first();

  if (!session || new Date(session.expires_at) < new Date()) return unauth();

  try {
    const { course, unit, lesson, status, score, max_score } = await request.json();

    if (!course || !unit || !lesson || !status) {
      return new Response(JSON.stringify({ ok: false, error: 'Missing required fields.' }), {
        status: 400, headers: corsHeaders('application/json'),
      });
    }

    const validStatuses = ['in_progress', 'complete'];
    if (!validStatuses.includes(status)) {
      return new Response(JSON.stringify({ ok: false, error: 'Invalid status.' }), {
        status: 400, headers: corsHeaders('application/json'),
      });
    }

    const completedAt = status === 'complete' ? new Date().toISOString() : null;
    const updatedAt = new Date().toISOString();

    await env.SPECIMEN_DB.prepare(
      `INSERT INTO lesson_progress (user_id, course, unit, lesson, status, score, max_score, completed_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id, course, unit, lesson) DO UPDATE SET
         status = excluded.status,
         score = excluded.score,
         max_score = excluded.max_score,
         completed_at = COALESCE(lesson_progress.completed_at, excluded.completed_at),
         updated_at = excluded.updated_at`
    ).bind(
      session.user_id, course, unit, lesson, status,
      score || 0, max_score || 0, completedAt, updatedAt
    ).run();

    return new Response(JSON.stringify({ ok: true }), {
      status: 200, headers: corsHeaders('application/json'),
    });

  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: 'Something went wrong.' }), {
      status: 500, headers: corsHeaders('application/json'),
    });
  }
}

function unauth() {
  return new Response(JSON.stringify({ ok: false, error: 'Not signed in.' }), {
    status: 401, headers: corsHeaders('application/json'),
  });
}
