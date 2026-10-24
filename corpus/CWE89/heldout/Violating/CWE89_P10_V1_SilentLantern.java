import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SilentLantern {

    public static String data;

    public void runSilentLantern() throws SQLException {
        data = System.getenv("SILENT_LANTERN_FILTER");
        (new CWE89_P10_V1_SilentLanternSink()).querySilentLantern();
    }
}

class CWE89_P10_V1_SilentLanternSink {
    public void querySilentLantern() throws SQLException {
        String data = CWE89_P10_V1_SilentLantern.data;
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
