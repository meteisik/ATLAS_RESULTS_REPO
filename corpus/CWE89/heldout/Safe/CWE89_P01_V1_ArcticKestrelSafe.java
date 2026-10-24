import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_ArcticKestrelSafe {

    public void runArcticKestrel() throws SQLException {
        String data;
        data = "foo";
        Connection arcticKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticKestrel");
        Statement arcticKestrelStatement = null;
        ResultSet arcticKestrelRows = null;
        try {
            arcticKestrelStatement = arcticKestrelConnection.createStatement();
            arcticKestrelRows = arcticKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticKestrelRows.getRow());
        } finally {
            if (arcticKestrelRows != null) {
                arcticKestrelRows.close();
            }
            if (arcticKestrelStatement != null) {
                arcticKestrelStatement.close();
            }
            arcticKestrelConnection.close();
        }
    }
}
