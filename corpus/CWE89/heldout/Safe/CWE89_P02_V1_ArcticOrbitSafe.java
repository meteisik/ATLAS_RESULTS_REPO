import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_ArcticOrbitSafe {

    public void runArcticOrbit() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
