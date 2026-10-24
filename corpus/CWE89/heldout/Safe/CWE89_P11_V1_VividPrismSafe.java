import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_VividPrismSafe {

    public void runVividPrism() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_VividPrismSafeSink()).queryVividPrism(dataHashMap);
    }
}

class CWE89_P11_V1_VividPrismSafeSink {
    public void queryVividPrism(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection vividPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividPrism");
        Statement vividPrismStatement = null;
        ResultSet vividPrismRows = null;
        try {
            vividPrismStatement = vividPrismConnection.createStatement();
            vividPrismRows = vividPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividPrismRows.getRow());
        } finally {
            if (vividPrismRows != null) {
                vividPrismRows.close();
            }
            if (vividPrismStatement != null) {
                vividPrismStatement.close();
            }
            vividPrismConnection.close();
        }
    }
}
