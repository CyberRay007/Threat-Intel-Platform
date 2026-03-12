"""add week6 score component columns

Revision ID: 0004_week6_scoring_components
Revises: 0003_week5_graph_intelligence
Create Date: 2026-03-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0004_week6_scoring_components"
down_revision = "0003_week5_graph_intelligence"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("feed_intel_score", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("historical_score", sa.Integer(), nullable=False, server_default="0"))

    op.add_column("scan_results", sa.Column("feed_intel_score", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("scan_results", sa.Column("historical_score", sa.Integer(), nullable=False, server_default="0"))


def downgrade():
    op.drop_column("scan_results", "historical_score")
    op.drop_column("scan_results", "feed_intel_score")

    op.drop_column("scans", "historical_score")
    op.drop_column("scans", "feed_intel_score")
