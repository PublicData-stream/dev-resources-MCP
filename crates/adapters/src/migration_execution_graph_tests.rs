//! Predecode admission checks independent of provider fixture shapes.
use super::*;
use serde_json::{Value, json};

fn nodes(value: &Value) -> usize {
    1 + match value {
        Value::Array(values) => values.iter().map(nodes).sum(),
        Value::Object(values) => values.values().map(nodes).sum(),
        _ => 0,
    }
}

#[test]
fn predecode_bound_covers_container_number_and_unicode_clones() {
    let mut nested = json!(null);
    for _ in 0..128 {
        nested = Value::Array(vec![nested]);
    }
    let wide: serde_json::Map<String, Value> = (0..4096)
        .map(|ordinal| (format!("entry-{ordinal}"), json!("가".repeat(257))))
        .collect();
    let cases = [
        json!(null),
        json!([]),
        json!({}),
        nested,
        Value::Object(wide),
        Value::Array((0..4096).map(|_| json!({"k":null})).collect()),
        json!("\0\n\"한글".repeat(4096)),
        serde_json::from_str::<Value>(&"9".repeat(16_384)).expect("exact large number"),
    ];
    for value in cases {
        let encoded = serde_json::to_vec(&value).expect("encode fixture");
        let estimated = MigrationExecution::graph_input_charge(encoded.len(), nodes(&value))
            .expect("bounded estimate");
        let decoded = MigrationExecution::graph_value_charge(&value).expect("decoded charge");
        assert!(
            estimated >= decoded * 3,
            "predecode estimate must cover three live decoded/envelope clones"
        );
    }
    assert!(MigrationExecution::graph_input_charge(usize::MAX, 1).is_err());
    assert!(MigrationExecution::graph_input_charge(1, usize::MAX).is_err());
}

#[test]
fn predecode_windows_keep_order_split_budget_and_allow_one_large_unit() {
    let execution = MigrationExecution::new_with_graph_options(
        MigrationExecutionOptions::new(8, 1024).expect("execution options"),
        MigrationGraphOptions::new(8).expect("graph options"),
    )
    .expect("execution");
    assert_eq!(
        execution
            .graph_input_window(vec![(0, 3), (1, 3), (2, 3)])
            .expect("prefix"),
        vec![(0, 3), (1, 3)]
    );
    assert_eq!(
        execution
            .graph_input_window(vec![(0, 9), (1, 1)])
            .expect("oversized prefix"),
        vec![(0, 9)]
    );
    assert!(execution.graph_input_window(vec![(0, 0)]).is_err());
    let one = MigrationExecution::new_with_graph_options(
        MigrationExecutionOptions::new(1, 1024).expect("execution options"),
        MigrationGraphOptions::new(8).expect("graph options"),
    )
    .expect("execution");
    assert_eq!(
        one.graph_input_window(vec![(0, 1), (1, 1)])
            .expect("worker prefix"),
        vec![(0, 1)]
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL; verifies scalar predecode metadata without schema changes"]
async fn postgres_graph_metadata_counts_every_container_and_scalar_before_decode() {
    let url = std::env::var("DEVRES_TEST_DATABASE_URL").expect("disposable database required");
    let pool = sqlx_postgres::PgPool::connect(&url)
        .await
        .expect("connect fixture PostgreSQL");
    for value in [
        json!(null),
        json!([]),
        json!({}),
        json!({"a":[1,{"b":[true,false,null]}],"escaped":"\n\"한글"}),
    ] {
        let (bytes,count):(i64,i64) = sqlx_core::query_as::query_as("SELECT octet_length($1::jsonb::text)::bigint,jsonb_array_length(jsonb_path_query_array($1::jsonb,'strict $.**.type()'))::bigint")
            .bind(sqlx_core::types::Json(&value)).fetch_one(&pool).await.expect("scalar source metadata");
        assert_eq!(
            count as usize,
            nodes(&value),
            "strict PostgreSQL traversal counts each value once"
        );
        let bound = MigrationExecution::graph_input_charge(bytes as usize, count as usize)
            .expect("source charge");
        assert!(
            bound >= MigrationExecution::graph_value_charge(&value).expect("decoded charge") * 3
        );
    }
    pool.close().await;
}
