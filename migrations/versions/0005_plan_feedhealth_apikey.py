"""add org plan, feed health table, and api key ip logging support

Revision ID: 0005_plan_feedhealth_apikey
Revises: 0004_week6_scoring_components
Create Date: 2026-03-17 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_plan_feedhealth_apikey"
down_revision = "0004_week6_scoring_components"
branch_labels = None
depends_on = None


def upgrade():
    # Add plan column to organizations
    op.add_column(
        "organizations",
        sa.Column("plan", sa.String(), nullable=False, server_default="free"),
    )

    # Feed health reliability table
    op.create_table(
        "feed_health",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("source", sa.String(), nullable=False, unique=True, index=True),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(), nullable=True),
        sa.Column("last_failure_message", sa.Text(), nullable=True),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("success_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("freshness_score", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table("feed_health")
    op.drop_column("organizations", "plan")
