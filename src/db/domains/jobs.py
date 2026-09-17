"""Jobs, hosts, and nmap results."""

from urllib.parse import urlparse

from sqlalchemy import select

from ..base import DatabaseCore, now, to_dict
from ..models import Host, HostNmap, HostWebApp, Job


class JobsMixin(DatabaseCore):
    @classmethod
    def create_job(cls, job_type="Normal", model=None, depth=4, comment=None, target_url=None):
        def action():
            jt = job_type if job_type in ("Normal", "IA") else "Normal"
            return cls._insert(
                Job, type=jt, model=model, depth=depth, comment=comment,
                target_url=target_url, state="running", timestamp=now(),
            )
        return cls._try(action)

    @classmethod
    def create_job_with_webapp(cls, url, job_type="Normal", model=None):
        def action():
            parsed = urlparse(url)
            if not parsed.hostname:
                raise ValueError(f"Invalid URL: could not extract host from '{url}'")

            target_host = parsed.hostname
            if parsed.port and parsed.port not in (80, 443):
                target_host += f":{parsed.port}"

            jt = job_type if job_type in ("Normal", "IA") else "Normal"
            job_id = cls._insert(
                Job, type=jt, model=model, depth=4, comment=None,
                target_url=url, state="running", timestamp=now(),
            )
            host_id = cls._insert(
                Host, jobs_id=job_id, target_host=target_host, state="done", timestamp=now(),
            )
            web_app_id = cls._insert(
                HostWebApp, host_id=host_id, target_url=url, state="done",
                jobs_id=job_id, timestamp=now(),
            )
            return {
                "job_id": job_id,
                "host_id": host_id,
                "web_app_id": web_app_id,
                "target_host": target_host,
                "target_url": url,
            }
        return cls._try(action)

    @classmethod
    def finish_job(cls, job_id, state="done", error_message=None):
        return cls._try(lambda: cls._update(Job, job_id, state=state, error_message=error_message, finished_at=now()))

    @classmethod
    def get_job(cls, job_id):
        return cls._try(lambda: cls._find_one(Job, id=job_id))

    @classmethod
    def get_latest_job(cls):
        return cls._try(lambda: cls._find_one_ordered(Job, [Job.timestamp.desc(), Job.id.desc()]))

    @classmethod
    def get_jobs(cls, job_id=None, ascending=False, reporter=False):
        return cls._try(lambda: cls._get_jobs(job_id, ascending, reporter), [])

    @classmethod
    def _get_jobs(cls, job_id: int = None, ascending: bool = False, reporter: bool = False):
        stmt = select(Job)
        if job_id:
            stmt = stmt.where(Job.id == job_id)
        stmt = stmt.order_by(Job.id.asc() if ascending else Job.id.desc())
        rows = []
        for job in cls._session().scalars(stmt).all():
            row = to_dict(job)
            if reporter:
                row["job_type"] = row.pop("type", None)
            rows.append(row)
        return rows

    @classmethod
    def delete_job(cls, job_id: int):
        return cls._try(lambda: cls._delete_job(job_id), 0)

    @classmethod
    def _delete_job(cls, job_id: int) -> int:
        session = cls._session()
        job = session.get(Job, job_id)
        if not job:
            return 0
        session.delete(job)
        session.commit()
        return 1

    @classmethod
    def get_running_jobs(cls):
        jobs = cls._session().scalars(select(Job).where(Job.state == "running")).all()
        return [{"id": job.id} for job in jobs]

    @classmethod
    def insert_host(cls, job_id, target_host, state="pending"):
        return cls._try(lambda: cls._insert(Host, jobs_id=job_id, target_host=target_host, state=state, timestamp=now()))

    @classmethod
    def update_host_state(cls, host_id, state, error_message=None):
        return cls._try(lambda: cls._update(Host, host_id, state=state, error_message=error_message) > 0)

    @classmethod
    def update_host_log(cls, host_id, log):
        return cls._try(lambda: cls._update(Host, host_id, log=log) > 0)

    @classmethod
    def get_host(cls, host_id):
        return cls._try(lambda: cls._find_one(Host, id=host_id))

    @classmethod
    def insert_nmap_results(cls, host_id, results):
        def action():
            jobs_id = cls._resolve_jobs_id("hosts", host_id)
            inserted_ids = [
                cls._insert(
                    HostNmap, host_id=host_id, port=r["port"], nmap_state=r["state"],
                    nmap_service=r.get("service"), nmap_version=r.get("version"),
                    state="done", jobs_id=jobs_id, timestamp=now(),
                )
                for r in results
            ]
            return {"inserted_count": len(inserted_ids), "nmap_ids": inserted_ids}
        return cls._try(action)
