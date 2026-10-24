import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_IvoryKestrelSafe {

    private String loadIvoryKestrel() {
        String data;
        data = "foo";
        return data;
    }

    public void runIvoryKestrel() throws SQLException {
        String data = loadIvoryKestrel();
        Connection ivoryKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryKestrel");
        Statement ivoryKestrelStatement = null;
        ResultSet ivoryKestrelRows = null;
        try {
            ivoryKestrelStatement = ivoryKestrelConnection.createStatement();
            ivoryKestrelRows = ivoryKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryKestrelRows.getRow());
        } finally {
            if (ivoryKestrelRows != null) {
                ivoryKestrelRows.close();
            }
            if (ivoryKestrelStatement != null) {
                ivoryKestrelStatement.close();
            }
            ivoryKestrelConnection.close();
        }
    }
}
