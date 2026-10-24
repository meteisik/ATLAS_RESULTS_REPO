import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_ArcticRavenSafe {
    private static boolean privateTrue = true;

    public void runArcticRaven() throws SQLException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_ArcticRavenSafeSink()).queryArcticRaven(dataHashMap);
    }
}

class CWE89_P11_V2_ArcticRavenSafeSink {
    public void queryArcticRaven(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection arcticRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticRaven");
        Statement arcticRavenStatement = null;
        ResultSet arcticRavenRows = null;
        try {
            arcticRavenStatement = arcticRavenConnection.createStatement();
            arcticRavenRows = arcticRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticRavenRows.getRow());
        } finally {
            if (arcticRavenRows != null) {
                arcticRavenRows.close();
            }
            if (arcticRavenStatement != null) {
                arcticRavenStatement.close();
            }
            arcticRavenConnection.close();
        }
    }
}
