import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_CobaltRaven {
    private static boolean privateTrue = true;

    public void runCobaltRaven() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("COBALT_RAVEN_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_CobaltRavenSink()).queryCobaltRaven(dataHashMap);
    }
}

class CWE89_P11_V2_CobaltRavenSink {
    public void queryCobaltRaven(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection cobaltRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltRaven");
        Statement cobaltRavenStatement = null;
        ResultSet cobaltRavenRows = null;
        try {
            cobaltRavenStatement = cobaltRavenConnection.createStatement();
            cobaltRavenRows = cobaltRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltRavenRows.getRow());
        } finally {
            if (cobaltRavenRows != null) {
                cobaltRavenRows.close();
            }
            if (cobaltRavenStatement != null) {
                cobaltRavenStatement.close();
            }
            cobaltRavenConnection.close();
        }
    }
}
