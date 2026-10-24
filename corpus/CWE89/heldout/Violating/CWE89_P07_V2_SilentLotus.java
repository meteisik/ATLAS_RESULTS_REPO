import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SilentLotus {
    private static boolean privateReturnsTrue() { return true; }

    public void runSilentLotus() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE89_P07_V2_SilentLotusSource()).loadSilentLotus();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_SilentLotusSource {
    public String loadSilentLotus() {
        String data;
        data = System.getenv("SILENT_LOTUS_FILTER");
        return data;
    }
}
