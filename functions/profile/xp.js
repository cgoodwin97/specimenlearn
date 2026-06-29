import { corsHeaders, getSessionToken, handleOptions } from '../_auth_utils.js';

const XP_VALUES = {
  lesson_answer: 15,
  lesson_complete: 25,
};

const LEVEL_THRESHOLDS = [0, 100, 300, 600, 1000, 1500, 2200, 3000, 4000, 5500];

const LEVEL_TITLES = [
  'Curious Mind', 'Microscopist', 'Lab Trainee', 'Field Researcher',
  'Lab Technician', 'Research Associate', 'Research Scientist',
  'Senior Scientist', 'Research Fellow', 'Principal Scientist',
];

function calcLevel(xp) {
  let level = 1;
  for (let i = LEVEL_THRESHOLDS.length - 1; i >= 0; i--) {
    if (xp >= LEVEL_THRESHOLDS[i]) { level = i + 1; break; }
  }
  return Math.min(level, 10);
}

function xpForNextLevel(level) {
  if (level >= 10) return null;
  return LEVEL_THRESHOLDS[level];
}

export async function onRequestOptions() {
  return handleOptions();
}

export async function onRequestPost({ request, env }) {
  const token = getSessionToken(request);
  if (!token) return unauth();

  const session = await env.SPECIMEN_DB.prepare(
    `SELECT s.expires_at, u.id as user_id, u.xp, u.level
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ?`
  ).bind(token).first();

  if (!session || new Date(session.expires_at) < new Date()) return unauth();

  try {
    const { action } = await request.json();

    if (!XP_VALUES[action]) {
      return new Response(JSON.stringify({ ok: false, error: 'Unknown action.' }), {
        status: 400, headers: corsHeaders('application/json'),
      });
    }

    const currentXp = session.xp || 0;
    const awarded = XP_VALUES[action];
    const newXp = currentXp + awarded;
    const newLevel = calcLevel(newXp);
    const currentLevel = session.level || 1;

    await env.SPECIMEN_DB.prepare(
      'UPDATE users SET xp = ?, level = ? WHERE id = ?'
    ).bind(newXp, newLevel, session.user_id).run();

    return new Response(JSON.stringify({
      ok: true,
      xp_awarded: awarded,
      xp: newXp,
      level: newLevel,
      title: LEVEL_TITLES[newLevel - 1],
      level_up: newLevel > currentLevel,
      next_level_xp: xpForNextLevel(newLevel),
    }), { status: 200, headers: corsHeaders('application/json') });

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
