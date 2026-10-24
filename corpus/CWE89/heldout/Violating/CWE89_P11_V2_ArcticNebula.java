import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_ArcticNebula {

    public void runArcticNebula() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_NEBULA_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_ArcticNebulaSink()).queryArcticNebula(dataHashMap);
    }
}

class CWE89_P11_V2_ArcticNebulaSink {
    public void queryArcticNebula(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection arcticNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticNebula");
        Statement arcticNebulaStatement = null;
        ResultSet arcticNebulaRows = null;
        try {
            arcticNebulaStatement = arcticNebulaConnection.createStatement();
            arcticNebulaRows = arcticNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticNebulaRows.getRow());
        } finally {
            if (arcticNebulaRows != null) {
                arcticNebulaRows.close();
            }
            if (arcticNebulaStatement != null) {
                arcticNebulaStatement.close();
            }
            arcticNebulaConnection.close();
        }
    }
}
