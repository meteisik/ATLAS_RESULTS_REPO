import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_ArcticHelixSafe {

    public void runArcticHelix() throws SQLException {
        String data;
        data = "foo";
        Connection arcticHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHelix");
        Statement arcticHelixStatement = null;
        ResultSet arcticHelixRows = null;
        try {
            arcticHelixStatement = arcticHelixConnection.createStatement();
            arcticHelixRows = arcticHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticHelixRows.getRow());
        } finally {
            if (arcticHelixRows != null) {
                arcticHelixRows.close();
            }
            if (arcticHelixStatement != null) {
                arcticHelixStatement.close();
            }
            arcticHelixConnection.close();
        }
    }
}
