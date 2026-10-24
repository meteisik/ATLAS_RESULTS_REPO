import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_VividGlintSafe {

    public void runVividGlint() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_VividGlintSafeSink()).queryVividGlint(dataHashMap);
    }
}

class CWE89_P11_V1_VividGlintSafeSink {
    public void queryVividGlint(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection vividGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividGlint");
        Statement vividGlintStatement = null;
        ResultSet vividGlintRows = null;
        try {
            vividGlintStatement = vividGlintConnection.createStatement();
            vividGlintRows = vividGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividGlintRows.getRow());
        } finally {
            if (vividGlintRows != null) {
                vividGlintRows.close();
            }
            if (vividGlintStatement != null) {
                vividGlintStatement.close();
            }
            vividGlintConnection.close();
        }
    }
}
