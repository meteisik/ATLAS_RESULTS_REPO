import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_ArcticOrbit {

    public void runArcticOrbit() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_ORBIT_FILTER");
        Connection arcticOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticOrbit");
        Statement arcticOrbitStatement = null;
        ResultSet arcticOrbitRows = null;
        try {
            arcticOrbitStatement = arcticOrbitConnection.createStatement();
            arcticOrbitRows = arcticOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticOrbitRows.getRow());
        } finally {
            if (arcticOrbitRows != null) {
                arcticOrbitRows.close();
            }
            if (arcticOrbitStatement != null) {
                arcticOrbitStatement.close();
            }
            arcticOrbitConnection.close();
        }
    }
}
