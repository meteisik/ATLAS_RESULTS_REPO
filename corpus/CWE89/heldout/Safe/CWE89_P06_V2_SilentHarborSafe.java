import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SilentHarborSafe {

    public void runSilentHarbor() throws SQLException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SilentHarborSafeSink()).querySilentHarbor(data);
    }
}

class CWE89_P06_V2_SilentHarborSafeSink {
    public void querySilentHarbor(String data) throws SQLException {
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
