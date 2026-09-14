// Package catalog holds signatures for the local AI services we know about.
package catalog

// Signature describes how to recognise one service and how to test it for
// missing authentication.
type Signature struct {
	Name string
	Kind string // llm-server | ui | image-gen | vector-db | notebook | workflow

	// Ports the service listens on by default.
	Ports []int

	// Substrings that may appear in the owning process name / executable path.
	ProcHints []string

	// FingerprintPath is fetched over HTTP to confirm identity.
	FingerprintPath string
	// FingerprintBody, if non-empty, must appear in the response body.
	FingerprintBody []string

	// AuthPath is an endpoint that should require credentials. A 2xx response
	// carrying AuthBody means the API is open to anyone who can reach the port.
	AuthPath string
	AuthBody []string

	// Doc points at the vendor's hardening guidance.
	Doc string
}

// Signatures is the full catalog. Ports overlap on purpose; the fingerprint
// step disambiguates.
var Signatures = []Signature{
	{
		Name: "Ollama", Kind: "llm-server",
		Ports:           []int{11434},
		ProcHints:       []string{"ollama"},
		FingerprintPath: "/", FingerprintBody: []string{"Ollama is running"},
		AuthPath: "/api/tags", AuthBody: []string{"\"models\""},
		Doc: "https://github.com/ollama/ollama/blob/main/docs/faq.md",
	},
	{
		Name: "LM Studio", Kind: "llm-server",
		Ports:           []int{1234},
		ProcHints:       []string{"lm studio", "lmstudio", "lms"},
		FingerprintPath: "/v1/models", FingerprintBody: []string{"\"object\"", "\"data\""},
		AuthPath: "/v1/models", AuthBody: []string{"\"data\""},
		Doc: "https://lmstudio.ai/docs/api",
	},
	{
		Name: "llama.cpp server", Kind: "llm-server",
		Ports:           []int{8080, 8000},
		ProcHints:       []string{"llama-server", "llama.cpp", "llama_cpp"},
		FingerprintPath: "/props", FingerprintBody: []string{"default_generation_settings", "chat_template"},
		AuthPath: "/props", AuthBody: []string{"default_generation_settings"},
		Doc: "https://github.com/ggml-org/llama.cpp/tree/master/tools/server",
	},
	{
		Name: "vLLM", Kind: "llm-server",
		Ports:           []int{8000},
		ProcHints:       []string{"vllm"},
		FingerprintPath: "/v1/models", FingerprintBody: []string{"\"object\""},
		AuthPath: "/v1/models", AuthBody: []string{"\"data\""},
		Doc: "https://docs.vllm.ai/",
	},
	{
		Name: "Jan", Kind: "llm-server",
		Ports:           []int{1337},
		ProcHints:       []string{"jan"},
		FingerprintPath: "/v1/models", FingerprintBody: []string{"\"data\""},
		AuthPath: "/v1/models", AuthBody: []string{"\"data\""},
		Doc: "https://jan.ai/docs",
	},
	{
		Name: "LocalAI", Kind: "llm-server",
		Ports:           []int{8080},
		ProcHints:       []string{"local-ai", "localai"},
		FingerprintPath: "/readyz", FingerprintBody: []string{"OK", "ok"},
		AuthPath: "/v1/models", AuthBody: []string{"\"data\""},
		Doc: "https://localai.io/",
	},
	{
		Name: "KoboldCpp", Kind: "llm-server",
		Ports:           []int{5001},
		ProcHints:       []string{"koboldcpp", "kobold"},
		FingerprintPath: "/api/v1/model", FingerprintBody: []string{"\"result\""},
		AuthPath: "/api/v1/model", AuthBody: []string{"\"result\""},
		Doc: "https://github.com/LostRuins/koboldcpp/wiki",
	},
	{
		Name: "Open WebUI", Kind: "ui",
		Ports:           []int{8080, 3000},
		ProcHints:       []string{"open-webui", "open_webui"},
		FingerprintPath: "/api/config", FingerprintBody: []string{"\"name\"", "features"},
		AuthPath: "/api/config", AuthBody: []string{"features"},
		Doc: "https://docs.openwebui.com/",
	},
	{
		Name: "AnythingLLM", Kind: "ui",
		Ports:           []int{3001},
		ProcHints:       []string{"anythingllm", "anything-llm"},
		FingerprintPath: "/api/ping", FingerprintBody: []string{"online"},
		Doc: "https://docs.anythingllm.com/",
	},
	{
		Name: "SillyTavern", Kind: "ui",
		Ports:           []int{8000},
		ProcHints:       []string{"sillytavern"},
		FingerprintPath: "/", FingerprintBody: []string{"SillyTavern"},
		Doc: "https://docs.sillytavern.app/",
	},
	{
		Name: "ComfyUI", Kind: "image-gen",
		Ports:           []int{8188},
		ProcHints:       []string{"comfyui", "comfy"},
		FingerprintPath: "/system_stats", FingerprintBody: []string{"\"system\"", "comfyui_version", "\"devices\""},
		AuthPath: "/system_stats", AuthBody: []string{"\"devices\""},
		Doc: "https://docs.comfy.org/",
	},
	{
		Name: "Stable Diffusion WebUI", Kind: "image-gen",
		Ports:           []int{7860},
		ProcHints:       []string{"stable-diffusion", "webui.py", "a1111", "automatic1111", "forge"},
		FingerprintPath: "/internal/ping", FingerprintBody: []string{"{}"},
		AuthPath: "/sdapi/v1/options", AuthBody: []string{"sd_model_checkpoint", "samples_save"},
		Doc: "https://github.com/AUTOMATIC1111/stable-diffusion-webui/wiki",
	},
	{
		Name: "text-generation-webui", Kind: "ui",
		Ports:           []int{7860, 5000},
		ProcHints:       []string{"text-generation-webui", "textgen"},
		FingerprintPath: "/v1/internal/model/info", FingerprintBody: []string{"model_name"},
		AuthPath: "/v1/models", AuthBody: []string{"\"data\""},
		Doc: "https://github.com/oobabooga/text-generation-webui/wiki",
	},
	{
		Name: "Qdrant", Kind: "vector-db",
		Ports:           []int{6333},
		ProcHints:       []string{"qdrant"},
		FingerprintPath: "/", FingerprintBody: []string{"qdrant"},
		AuthPath: "/collections", AuthBody: []string{"\"result\""},
		Doc: "https://qdrant.tech/documentation/guides/security/",
	},
	{
		Name: "Chroma", Kind: "vector-db",
		Ports:           []int{8000},
		ProcHints:       []string{"chroma"},
		FingerprintPath: "/api/v1/heartbeat", FingerprintBody: []string{"nanosecond heartbeat"},
		AuthPath: "/api/v1/collections", AuthBody: []string{"["},
		Doc: "https://docs.trychroma.com/",
	},
	{
		Name: "Weaviate", Kind: "vector-db",
		Ports:           []int{8080},
		ProcHints:       []string{"weaviate"},
		FingerprintPath: "/v1/meta", FingerprintBody: []string{"\"version\"", "hostname"},
		AuthPath: "/v1/schema", AuthBody: []string{"classes"},
		Doc: "https://weaviate.io/developers/weaviate/configuration/authentication",
	},
	{
		Name: "Milvus", Kind: "vector-db",
		Ports:     []int{19530, 9091},
		ProcHints: []string{"milvus"},
		Doc:       "https://milvus.io/docs/authenticate.md",
	},
	{
		Name: "Jupyter", Kind: "notebook",
		Ports:           []int{8888},
		ProcHints:       []string{"jupyter", "jupyter-lab", "jupyter-notebook"},
		FingerprintPath: "/api/status", FingerprintBody: []string{"\"started\"", "kernels"},
		AuthPath: "/api/kernels", AuthBody: []string{"["},
		Doc: "https://jupyter-notebook.readthedocs.io/en/stable/security.html",
	},
	{
		Name: "Ray Dashboard", Kind: "workflow",
		Ports:           []int{8265},
		ProcHints:       []string{"ray", "raylet"},
		FingerprintPath: "/api/version", FingerprintBody: []string{"ray_version"},
		AuthPath: "/api/jobs/", AuthBody: []string{"["},
		Doc: "https://docs.ray.io/en/latest/ray-security/index.html",
	},
	{
		Name: "n8n", Kind: "workflow",
		Ports:           []int{5678},
		ProcHints:       []string{"n8n"},
		FingerprintPath: "/healthz", FingerprintBody: []string{"\"status\""},
		Doc: "https://docs.n8n.io/hosting/securing/",
	},
	{
		Name: "Flowise", Kind: "workflow",
		Ports:           []int{3000},
		ProcHints:       []string{"flowise"},
		FingerprintPath: "/api/v1/ping", FingerprintBody: []string{"pong"},
		AuthPath: "/api/v1/chatflows", AuthBody: []string{"["},
		Doc: "https://docs.flowiseai.com/configuration/authorization",
	},
	{
		Name: "Dify", Kind: "workflow",
		Ports:           []int{5001},
		ProcHints:       []string{"dify"},
		FingerprintPath: "/health", FingerprintBody: []string{"\"status\""},
		Doc: "https://docs.dify.ai/",
	},
}

// PortIndex maps a port to every signature that claims it.
func PortIndex() map[int][]Signature {
	idx := map[int][]Signature{}
	for _, s := range Signatures {
		for _, p := range s.Ports {
			idx[p] = append(idx[p], s)
		}
	}
	return idx
}

// AllPorts returns every port in the catalog, de-duplicated.
func AllPorts() []int {
	seen := map[int]bool{}
	var out []int
	for _, s := range Signatures {
		for _, p := range s.Ports {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}
