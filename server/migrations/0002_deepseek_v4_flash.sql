INSERT OR IGNORE INTO model_prices(id,model,mode,input_per_million_micros,output_per_million_micros,cache_per_million_micros,night_input_per_million_micros,night_output_per_million_micros,night_cache_per_million_micros,effective_from,active)
VALUES('price-dsv4f-001','DeepSeek-V4-Flash','pay_as_you_go',2000000,8000000,40000,1000000,4000000,20000,'2026-11-07T00:00:00+08:00',1);

UPDATE model_protocols SET model='DeepSeek-V4-Flash',base_url='https://moma.cmecloud.cn/tokenplan-personal/v1',upstream_model='DeepSeek-V4-Flash',enabled=1 WHERE id='proto-openai';
UPDATE model_protocols SET enabled=0 WHERE id IN ('proto-anthropic','proto-dashscope');
