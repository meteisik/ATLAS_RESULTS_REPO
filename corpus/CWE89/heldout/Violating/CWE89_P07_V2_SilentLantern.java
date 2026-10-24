import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SilentLantern {
    private static int privateFive = 5;

    public void runSilentLantern() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = (new CWE89_P07_V2_SilentLanternSource()).loadSilentLantern();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_SilentLanternSource {
    public String loadSilentLantern() {
        String data;
        data = System.getenv("SILENT_LANTERN_FILTER");
        return data;
    }
}
