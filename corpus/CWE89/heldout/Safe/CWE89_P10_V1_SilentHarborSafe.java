import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SilentHarborSafe {

    public static String data;

    public void runSilentHarbor() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_SilentHarborSafeSink()).querySilentHarbor();
    }
}

class CWE89_P10_V1_SilentHarborSafeSink {
    public void querySilentHarbor() throws SQLException {
        String data = CWE89_P10_V1_SilentHarborSafe.data;
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
