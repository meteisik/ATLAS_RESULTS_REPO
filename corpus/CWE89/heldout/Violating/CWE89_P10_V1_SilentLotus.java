import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SilentLotus {

    public static String data;

    public void runSilentLotus() throws SQLException {
        data = System.getenv("SILENT_LOTUS_FILTER");
        (new CWE89_P10_V1_SilentLotusSink()).querySilentLotus();
    }
}

class CWE89_P10_V1_SilentLotusSink {
    public void querySilentLotus() throws SQLException {
        String data = CWE89_P10_V1_SilentLotus.data;
        Connection silentLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLotus");
        Statement silentLotusStatement = null;
        ResultSet silentLotusRows = null;
        try {
            silentLotusStatement = silentLotusConnection.createStatement();
            silentLotusRows = silentLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentLotusRows.getRow());
        } finally {
            if (silentLotusRows != null) {
                silentLotusRows.close();
            }
            if (silentLotusStatement != null) {
                silentLotusStatement.close();
            }
            silentLotusConnection.close();
        }
    }
}
