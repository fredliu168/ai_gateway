ALTER TABLE model_prices ADD COLUMN video_480p_micros_per_second INTEGER NOT NULL DEFAULT 0;
ALTER TABLE model_prices ADD COLUMN video_720p_micros_per_second INTEGER NOT NULL DEFAULT 0;
ALTER TABLE model_prices ADD COLUMN video_1080p_micros_per_second INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO model_routes(id,display_name,source,model_key,upstream_model,protocol,endpoint,billing_mode,enabled,credential_ciphertext)
VALUES('route-happyhorse-1-1-t2v','HappyHorse-1.1-T2V','通义实验室','happyhorse-1.1-t2v','qwen/happyhorse-1.1-t2v','dashscope','https://moma.cmecloud.cn/api/v1/services/aigc/video-generation/video-synthesis','pay_as_you_go',0,NULL);

INSERT OR IGNORE INTO model_prices(id,model,mode,input_per_million_micros,output_per_million_micros,cache_per_million_micros,night_input_per_million_micros,night_output_per_million_micros,night_cache_per_million_micros,input_image_1k_micros,input_image_2k_micros,output_image_1k_micros,output_image_2k_micros,video_480p_micros_per_second,video_720p_micros_per_second,video_1080p_micros_per_second,effective_from,active)
VALUES('price-happyhorse-1-1-t2v-20260710','happyhorse-1.1-t2v','pay_as_you_go',0,0,0,0,0,0,0,0,0,0,450000,900000,1200000,'2026-07-10T00:00:00+08:00',1);
