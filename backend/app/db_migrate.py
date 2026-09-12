"""
Automatic SQLite schema synchronization.
Ensures all columns defined in SQLAlchemy models exist in SQLite database
without requiring manual Alembic migrations for local development.
"""

import logging
from sqlalchemy import inspect, text
from app.database import engine, Base
from app import models  # ensure all models are imported

logger = logging.getLogger("db_migrate")

COLUMN_DEFINITIONS = {
    "scans": [
        ("overall_risk_score", "FLOAT DEFAULT 0.0"),
        ("priority", "VARCHAR DEFAULT 'P4'"),
        ("actionable_count", "INTEGER DEFAULT 0"),
        ("informational_count", "INTEGER DEFAULT 0"),
        ("chains_count", "INTEGER DEFAULT 0"),
    ],
    "endpoints": [
        ("category", "VARCHAR DEFAULT 'api'"),
    ],
    "findings": [
        ("chain_aware_severity", "VARCHAR"),
        ("source", "VARCHAR DEFAULT 'nuclei'"),
        ("validity", "VARCHAR DEFAULT 'actionable'"),
        ("exploitability", "VARCHAR DEFAULT 'medium'"),
        ("risk_score", "FLOAT DEFAULT 5.0"),
        ("priority", "VARCHAR DEFAULT 'P3'"),
        ("safe_payload_test", "TEXT"),
        ("duplicate_count", "INTEGER DEFAULT 1"),
    ],
}


def auto_migrate():
    """Create missing tables and add any missing columns to existing SQLite tables."""
    # 1. Create tables if they don't exist
    Base.metadata.create_all(bind=engine)

    # 2. Check each table for missing columns
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table_name, columns in COLUMN_DEFINITIONS.items():
            if not inspector.has_table(table_name):
                continue
            existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
            for col_name, col_type in columns:
                if col_name not in existing_cols:
                    logger.info(f"Auto-migrating: adding column {col_name} to table {table_name}")
                    try:
                        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}"))
                    except Exception as e:
                        logger.warning(f"Failed to add column {col_name} to {table_name}: {e}")
