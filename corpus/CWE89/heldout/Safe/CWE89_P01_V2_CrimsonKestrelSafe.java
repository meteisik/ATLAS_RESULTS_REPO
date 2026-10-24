import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_CrimsonKestrelSafe {

    public void runCrimsonKestrel() throws SQLException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        Connection crimsonKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonKestrel");
        Statement crimsonKestrelStatement = null;
        ResultSet crimsonKestrelRows = null;
        try {
            crimsonKestrelStatement = crimsonKestrelConnection.createStatement();
            crimsonKestrelRows = crimsonKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonKestrelRows.getRow());
        } finally {
            if (crimsonKestrelRows != null) {
                crimsonKestrelRows.close();
            }
            if (crimsonKestrelStatement != null) {
                crimsonKestrelStatement.close();
            }
            crimsonKestrelConnection.close();
        }
    }
}
