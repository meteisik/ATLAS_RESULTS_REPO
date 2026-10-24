import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CobaltOrbit {

    public void runCobaltOrbit() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("COBALT_ORBIT_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection cobaltOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltOrbit");
            Statement cobaltOrbitStatement = null;
            ResultSet cobaltOrbitRows = null;
            try {
                cobaltOrbitStatement = cobaltOrbitConnection.createStatement();
                cobaltOrbitRows = cobaltOrbitStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(cobaltOrbitRows.getRow());
            } finally {
                if (cobaltOrbitRows != null) {
                    cobaltOrbitRows.close();
                }
                if (cobaltOrbitStatement != null) {
                    cobaltOrbitStatement.close();
                }
                cobaltOrbitConnection.close();
            }
        }
    }
}
