from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.models import WAFRule
from app.schemas.schemas import WAFRuleCreate, WAFRuleUpdate, RuleRead

router = APIRouter(prefix="/waf/rules", tags=["WAF Policy Rules"])

@router.get("", response_model=List[RuleRead])
def list_waf_rules(db: Session = Depends(get_db)):
    """Lists all configurable WAF signature detection rules."""
    rules = db.query(WAFRule).order_by(WAFRule.rule_id).all()
    return [
        RuleRead(
            rule_id=r.rule_id,
            name=r.name,
            category=r.category,
            severity=r.severity,
            pattern=r.pattern,
            description=r.description or "",
            is_active=r.is_active,
            hits_count=r.hits_count
        )
        for r in rules
    ]

@router.post("", response_model=RuleRead)
def create_waf_rule(payload: WAFRuleCreate, db: Session = Depends(get_db)):
    """Deploys a new custom WAF signature rule."""
    existing = db.query(WAFRule).filter(WAFRule.rule_id == payload.rule_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Rule ID {payload.rule_id} already exists.")

    new_rule = WAFRule(
        rule_id=payload.rule_id,
        name=payload.name,
        description=payload.description,
        category=payload.category,
        pattern=payload.pattern,
        severity=payload.severity,
        default_action=payload.default_action,
        is_active=payload.is_active,
        hits_count=0
    )
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)

    return RuleRead(
        rule_id=new_rule.rule_id,
        name=new_rule.name,
        category=new_rule.category,
        severity=new_rule.severity,
        pattern=new_rule.pattern,
        description=new_rule.description,
        is_active=new_rule.is_active,
        hits_count=new_rule.hits_count
    )

@router.patch("/{rule_id}", response_model=RuleRead)
def toggle_waf_rule(rule_id: str, payload: WAFRuleUpdate, db: Session = Depends(get_db)):
    """Toggles or updates a WAF rule."""
    rule = db.query(WAFRule).filter(WAFRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found.")

    if payload.is_active is not None:
        rule.is_active = payload.is_active
    if payload.name:
        rule.name = payload.name
    if payload.description:
        rule.description = payload.description
    if payload.pattern:
        rule.pattern = payload.pattern
    if payload.severity:
        rule.severity = payload.severity
    if payload.default_action:
        rule.default_action = payload.default_action

    db.commit()
    db.refresh(rule)

    return RuleRead(
        rule_id=rule.rule_id,
        name=rule.name,
        category=rule.category,
        severity=rule.severity,
        pattern=rule.pattern,
        description=rule.description or "",
        is_active=rule.is_active,
        hits_count=rule.hits_count
    )
