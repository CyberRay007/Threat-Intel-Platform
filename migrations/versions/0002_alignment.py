"""align week3 intelligence fields and jsonb names

Revision ID: 0002_week3_alignment
Revises: 0001_extend_schema
Create Date: 2026-03-08 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0002_week3_alignment"
down_revision = "0001_extend_schema"
branch_labels = None
depends_on = None


def upgrade():
    # Week 3 requested fields directly on scans table
    op.add_column("scans", sa.Column("structural_score", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("vt_score", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"))
    op.add_column(
        "scans",
        sa.Column("signals", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "scans",
        sa.Column("vt_response", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )

    # Week 3 canonical names on scan_results while retaining legacy columns
    op.add_column(
        "scan_results",
        sa.Column("signals", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "scan_results",
        sa.Column("vt_response", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )

    # Backfill new canonical fields from existing legacy JSON fields.
    op.execute("UPDATE scan_results SET signals = COALESCE(signals_json::jsonb, '{}'::jsonb)")
    op.execute("UPDATE scan_results SET vt_response = COALESCE(vt_raw_json::jsonb, '{}'::jsonb)")


def downgrade():
    op.drop_column("scan_results", "vt_response")
    op.drop_column("scan_results", "signals")

    op.drop_column("scans", "vt_response")
    op.drop_column("scans", "signals")
    op.drop_column("scans", "risk_score")
    op.drop_column("scans", "vt_score")
    op.drop_column("scans", "structural_score")
