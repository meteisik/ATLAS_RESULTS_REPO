import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SilentLanternSafe {
    private static boolean privateTrue = true;

    public void runSilentLantern() throws SQLException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SilentLanternSafeSink()).querySilentLantern(data);
    }
}

class CWE89_P06_V2_SilentLanternSafeSink {
    public void querySilentLantern(String data) throws SQLException {
        Connection silentLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLantern");
        Statement silentLanternStatement = null;
        ResultSet silentLanternRows = null;
        try {
            silentLanternStatement = silentLanternConnection.createStatement();
            silentLanternRows = silentLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentLanternRows.getRow());
        } finally {
            if (silentLanternRows != null) {
                silentLanternRows.close();
            }
            if (silentLanternStatement != null) {
                silentLanternStatement.close();
            }
            silentLanternConnection.close();
        }
    }
}
