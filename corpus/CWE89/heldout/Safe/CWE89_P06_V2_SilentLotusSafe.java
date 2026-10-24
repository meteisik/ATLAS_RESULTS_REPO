import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SilentLotusSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runSilentLotus() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SilentLotusSafeSink()).querySilentLotus(data);
    }
}

class CWE89_P06_V2_SilentLotusSafeSink {
    public void querySilentLotus(String data) throws SQLException {
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
