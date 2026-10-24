import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_IvoryLotusSafe {

    private String loadIvoryLotus() {
        String data;
        data = "foo";
        return data;
    }

    public void runIvoryLotus() throws SQLException {
        String data = loadIvoryLotus();
        Connection ivoryLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryLotus");
        Statement ivoryLotusStatement = null;
        ResultSet ivoryLotusRows = null;
        try {
            ivoryLotusStatement = ivoryLotusConnection.createStatement();
            ivoryLotusRows = ivoryLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryLotusRows.getRow());
        } finally {
            if (ivoryLotusRows != null) {
                ivoryLotusRows.close();
            }
            if (ivoryLotusStatement != null) {
                ivoryLotusStatement.close();
            }
            ivoryLotusConnection.close();
        }
    }
}
