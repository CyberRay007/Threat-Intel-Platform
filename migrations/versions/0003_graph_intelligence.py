"""add graph intelligence tables (week 5)

Revision ID: 0003_week5_graph_intelligence
Revises: 0002_week3_alignment
Create Date: 2026-03-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0003_week5_graph_intelligence"
down_revision = "0002_week3_alignment"
branch_labels = None
depends_on = None


def upgrade():
    # ------------------------------------------------------------------
    # Rename existing singular table to canonical plural form
    # ------------------------------------------------------------------
    op.rename_table("threat_actor", "threat_actors")

    # Add new columns to threat_actors
    op.add_column("threat_actors", sa.Column("origin", sa.String(), nullable=True))
    op.add_column(
        "threat_actors",
        sa.Column(
            "aliases",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "threat_actors",
        sa.Column("created_at", sa.DateTime(), nullable=True, server_default=sa.text("now()")),
    )
    # Enforce unique names now that multiple feeds may insert actors
    op.create_index("ix_threat_actors_name", "threat_actors", ["name"], unique=True)

    # Update the FK on the ioc table to point to the renamed table
    op.drop_constraint("ioc_threat_actor_id_fkey", "ioc", type_="foreignkey")
    op.create_foreign_key(
        "ioc_threat_actor_id_fkey",
        "ioc",
        "threat_actors",
        ["threat_actor_id"],
        ["id"],
    )

    # ------------------------------------------------------------------
    # malware_families
    # ------------------------------------------------------------------
    op.create_table(
        "malware_families",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("family_type", sa.String(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "aliases",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(), nullable=True, server_default=sa.text("now()")),
        sa.UniqueConstraint("name", name="uq_malware_families_name"),
    )
    op.create_index("ix_malware_families_id", "malware_families", ["id"])
    op.create_index("ix_malware_families_name", "malware_families", ["name"], unique=True)

    # ------------------------------------------------------------------
    # campaigns
    # ------------------------------------------------------------------
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("threat_actor_id", sa.Integer(), sa.ForeignKey("threat_actors.id"), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True, server_default=sa.text("now()")),
        sa.UniqueConstraint("name", name="uq_campaigns_name"),
    )
    op.create_index("ix_campaigns_id", "campaigns", ["id"])
    op.create_index("ix_campaigns_name", "campaigns", ["name"], unique=True)
    op.create_index("ix_campaigns_threat_actor_id", "campaigns", ["threat_actor_id"])

    # ------------------------------------------------------------------
    # ioc_relationships
    # ------------------------------------------------------------------
    op.create_table(
        "ioc_relationships",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ioc_id", sa.Integer(), sa.ForeignKey("ioc.id"), nullable=False),
        sa.Column("relationship_type", sa.String(), nullable=False),
        sa.Column("related_entity_type", sa.String(), nullable=False),
        sa.Column("related_entity_id", sa.Integer(), nullable=False),
        sa.Column("threat_actor_id", sa.Integer(), sa.ForeignKey("threat_actors.id"), nullable=True),
        sa.Column("malware_family_id", sa.Integer(), sa.ForeignKey("malware_families.id"), nullable=True),
        sa.Column("campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id"), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("created_at", sa.DateTime(), nullable=True, server_default=sa.text("now()")),
        sa.UniqueConstraint(
            "ioc_id", "relationship_type", "related_entity_type", "related_entity_id",
            name="uq_ioc_relationship",
        ),
    )
    op.create_index("ix_ioc_relationships_id", "ioc_relationships", ["id"])
    op.create_index("ix_ioc_relationships_ioc_id", "ioc_relationships", ["ioc_id"])
    op.create_index("ix_ioc_relationships_threat_actor_id", "ioc_relationships", ["threat_actor_id"])
    op.create_index("ix_ioc_relationships_malware_family_id", "ioc_relationships", ["malware_family_id"])
    op.create_index("ix_ioc_relationships_campaign_id", "ioc_relationships", ["campaign_id"])


def downgrade():
    op.drop_table("ioc_relationships")
    op.drop_table("campaigns")
    op.drop_table("malware_families")

    # Restore FK to old table name before renaming back
    op.drop_constraint("ioc_threat_actor_id_fkey", "ioc", type_="foreignkey")
    op.rename_table("threat_actors", "threat_actor")
    op.create_foreign_key(
        "ioc_threat_actor_id_fkey",
        "ioc",
        "threat_actor",
        ["threat_actor_id"],
        ["id"],
    )

    op.drop_index("ix_threat_actors_name", table_name="threat_actor")
    op.drop_column("threat_actor", "created_at")
    op.drop_column("threat_actor", "aliases")
    op.drop_column("threat_actor", "origin")
