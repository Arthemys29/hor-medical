-- ============================================================================
-- SCRIPT D'INITIALISATION - Adapté pour Railway
-- Secure Medical Monitor - Université de Kara
-- Année académique : 2025-2026
-- ============================================================================

-- UTILISATEURS CRÉÉS:
--   👤 directeur   / Directeur@123  → Rôle: directeur (accès complet)
--   👤 soc         / Soc@123        → Rôle: security (surveillance sécurité)
--   👤 infirmier1  / Infirmier@123  → Rôle: infirmier (gestion patients)
--   👤 infirmier2  / Infirmier@123  → Rôle: infirmier (gestion patients)

-- NOTE RAILWAY: On ne DROP/CREATE pas la DB, on repart de zéro
-- en supprimant les objets existants dans l'ordre correct.

-- ─────────────────────────────────────────────────────────────────────────────
-- ÉTAPE 0: NETTOYAGE (drop dans l'ordre des dépendances)
-- ─────────────────────────────────────────────────────────────────────────────

DROP VIEW IF EXISTS v_active_alerts CASCADE;
DROP VIEW IF EXISTS v_event_stats CASCADE;

DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS security_events CASCADE;
DROP TABLE IF EXISTS consultations CASCADE;
DROP TABLE IF EXISTS patients CASCADE;
DROP TABLE IF EXISTS users CASCADE;

DROP TYPE IF EXISTS user_role CASCADE;
DROP TYPE IF EXISTS severity_level CASCADE;
DROP TYPE IF EXISTS alert_level CASCADE;
DROP TYPE IF EXISTS sexe_type CASCADE;
DROP TYPE IF EXISTS confidentialite_level CASCADE;

-- ─────────────────────────────────────────────────────────────────────────────
-- ÉTAPE 1: TYPES ENUM
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TYPE user_role AS ENUM ('directeur', 'security', 'infirmier');
CREATE TYPE severity_level AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE alert_level AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE sexe_type AS ENUM ('M', 'F');
CREATE TYPE confidentialite_level AS ENUM ('normal', 'confidentiel', 'secret');

-- ─────────────────────────────────────────────────────────────────────────────
-- ÉTAPE 2: TABLES
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL,
    is_locked BOOLEAN DEFAULT FALSE,
    failed_attempts INTEGER DEFAULT 0,
    last_failed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(50)
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_locked ON users(is_locked);

CREATE TABLE patients (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(100) NOT NULL,
    prenom VARCHAR(100) NOT NULL,
    date_naissance VARCHAR(20) NOT NULL,
    sexe sexe_type NOT NULL,
    adresse TEXT,
    telephone VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_patients_nom ON patients(nom);
CREATE INDEX idx_patients_prenom ON patients(prenom);
CREATE INDEX idx_patients_created ON patients(created_at);

CREATE TABLE consultations (
    id SERIAL PRIMARY KEY,
    patient_id INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    infirmier_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    date_visite TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    poids FLOAT,
    tension_arterielle VARCHAR(20),
    temperature FLOAT,
    frequence_cardiaque INTEGER,
    saturation_o2 FLOAT,
    diagnostic TEXT NOT NULL,
    traitement TEXT NOT NULL,
    observations TEXT,
    niveau_confidentialite confidentialite_level DEFAULT 'normal',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_consultations_patient ON consultations(patient_id);
CREATE INDEX idx_consultations_infirmier ON consultations(infirmier_id);
CREATE INDEX idx_consultations_date ON consultations(date_visite);

CREATE TABLE security_events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(100),
    ip_address VARCHAR(45),
    event_type VARCHAR(80) NOT NULL,
    severity severity_level NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'detected',
    action_taken TEXT
);

CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_username ON security_events(username);
CREATE INDEX idx_security_events_ip ON security_events(ip_address);
CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_severity ON security_events(severity);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alert_level alert_level NOT NULL,
    source_event_id INTEGER REFERENCES security_events(id) ON DELETE SET NULL,
    message TEXT NOT NULL,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(50)
);

CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_level ON alerts(alert_level);
CREATE INDEX idx_alerts_resolved ON alerts(resolved);
CREATE INDEX idx_alerts_source ON alerts(source_event_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- ÉTAPE 3: DONNÉES DE BASE
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO users (username, full_name, password_hash, role, created_by) VALUES
('directeur',
 'Kpoda Abdel',
 '$2b$12$1Y9HD1fb0RaX332FhKgeWOQMLj1PW32N0tvnFFssrUwD1Kc5C7iWq',
 'directeur',
 'Système'),

('soc',
 'William Smith',
 '$2b$12$Kl.G3qFVp2iAmXtBroFXNeSwYmDLpMqee.w3BajuG2i.iCl7AfYUO',
 'security',
 'Système'),

('infirmier1',
 'Jean Dupont',
 '$2b$12$CiAzcxQMi3CC6pOlEbXR7.O7ez5LWvoyPm4qWOG2i2rt3304tPx2q',
 'infirmier',
 'Système'),

('infirmier2',
 'Marie Curie',
 '$2b$12$CiAzcxQMi3CC6pOlEbXR7.O7ez5LWvoyPm4qWOG2i2rt3304tPx2q',
 'infirmier',
 'Système');

INSERT INTO patients (nom, prenom, date_naissance, sexe, adresse, telephone) VALUES
('DUPONT',  'Jean',   '1985-03-15', 'M', '12 Rue de la Paix, Paris',                    '06 12 34 56 78'),
('MARTIN',  'Sophie', '1990-07-22', 'F', '45 Avenue des Champs-Élysées, Lyon',           '06 98 76 54 32'),
('BERNARD', 'Pierre', '1978-11-08', 'M', '78 Boulevard de la Liberté, Marseille',        '06 11 22 33 44');

INSERT INTO consultations (patient_id, infirmier_id, poids, tension_arterielle, temperature,
                           frequence_cardiaque, saturation_o2, diagnostic, traitement,
                           observations, niveau_confidentialite) VALUES
(1, 3, 75.5, '120/80', 37.2, 72, 98.0,
 'Hypertension artérielle stade 1',
 'IEC 10mg/jour, régime hyposodé, surveillance tension',
 'Patient fumeur, conseils d''arrêt donnés', 'normal'),

(2, 3, 62.0, '110/70', 38.5, 85, 97.0,
 'Infection respiratoire haute',
 'Antibiotiques 5 jours, antipyrétique, repos',
 'Fièvre importante, à recontrôler dans 48h', 'normal');

-- ─────────────────────────────────────────────────────────────────────────────
-- ÉTAPE 4: VUES
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE VIEW v_event_stats AS
SELECT
    severity,
    COUNT(*) as count,
    COUNT(CASE WHEN status = 'detected' THEN 1 END) as detected_count,
    COUNT(CASE WHEN status = 'closed' THEN 1 END) as closed_count
FROM security_events
GROUP BY severity;

CREATE OR REPLACE VIEW v_active_alerts AS
SELECT
    id,
    timestamp,
    alert_level,
    message,
    source_event_id
FROM alerts
WHERE resolved = FALSE
ORDER BY timestamp DESC;

-- ─────────────────────────────────────────────────────────────────────────────
-- ÉTAPE 5: PERMISSIONS
-- ─────────────────────────────────────────────────────────────────────────────

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public TO postgres;