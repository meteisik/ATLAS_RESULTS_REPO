import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_CrimsonHelixSafe {

    private void queryCrimsonHelix(String data) throws SQLException {
        Connection crimsonHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHelix");
        Statement crimsonHelixStatement = null;
        ResultSet crimsonHelixRows = null;
        try {
            crimsonHelixStatement = crimsonHelixConnection.createStatement();
            crimsonHelixRows = crimsonHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonHelixRows.getRow());
        } finally {
            if (crimsonHelixRows != null) {
                crimsonHelixRows.close();
            }
            if (crimsonHelixStatement != null) {
                crimsonHelixStatement.close();
            }
            crimsonHelixConnection.close();
        }
    }

    public void runCrimsonHelix() throws SQLException {
        String data;
        data = "foo";
        queryCrimsonHelix(data);
    }
}
