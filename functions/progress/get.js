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

  const url = new URL(request.url);
  const course = url.searchParams.get('course');

  if (!course) {
    return new Response(JSON.stringify({ ok: false, error: 'Missing course parameter.' }), {
      status: 400, headers: corsHeaders('application/json'),
    });
  }

  const { results } = await env.SPECIMEN_DB.prepare(
    `SELECT unit, lesson, status, score, max_score, completed_at
     FROM lesson_progress
     WHERE user_id = ? AND course = ?
     ORDER BY unit ASC, lesson ASC`
  ).bind(session.user_id, course).all();

  return new Response(JSON.stringify({ ok: true, progress: results || [] }), {
    status: 200, headers: corsHeaders('application/json'),
  });
}

function unauth() {
  return new Response(JSON.stringify({ ok: false, error: 'Not signed in.' }), {
    status: 401, headers: corsHeaders('application/json'),
  });
}
