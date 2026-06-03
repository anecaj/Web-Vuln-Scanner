import axios from "axios";
const BASE = import.meta.env.VITE_API_URL || "/api";
const api = axios.create({ baseURL: BASE });
export const startScan  = (url) => api.post("/scan", { url });
export const getScan    = (id)  => api.get(`/scan/${id}`);
export const listScans  = ()    => api.get("/scans");
