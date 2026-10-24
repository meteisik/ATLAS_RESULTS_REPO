import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CrimsonKestrelSafe {

    public void runCrimsonKestrel() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
