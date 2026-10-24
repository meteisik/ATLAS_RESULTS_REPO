import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SilentHarbor {
    private static boolean privateTrue = true;

    public void runSilentHarbor() throws SQLException {
        String data;
        if (privateTrue) {
            data = (new CWE89_P07_V2_SilentHarborSource()).loadSilentHarbor();
        } else {
            data = null;
        }
        Connection silentHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentHarbor");
        Statement silentHarborStatement = null;
        ResultSet silentHarborRows = null;
        try {
            silentHarborStatement = silentHarborConnection.createStatement();
            silentHarborRows = silentHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentHarborRows.getRow());
        } finally {
            if (silentHarborRows != null) {
                silentHarborRows.close();
            }
            if (silentHarborStatement != null) {
                silentHarborStatement.close();
            }
            silentHarborConnection.close();
        }
    }
}

class CWE89_P07_V2_SilentHarborSource {
    public String loadSilentHarbor() {
        String data;
        data = System.getenv("SILENT_HARBOR_FILTER");
        return data;
    }
}
