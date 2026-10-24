import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetSundial {

    public static String data;

    public void runVelvetSundial() throws SQLException {
        data = System.getenv("VELVET_SUNDIAL_FILTER");
        (new CWE89_P10_V1_VelvetSundialSink()).queryVelvetSundial();
    }
}

class CWE89_P10_V1_VelvetSundialSink {
    public void queryVelvetSundial() throws SQLException {
        String data = CWE89_P10_V1_VelvetSundial.data;
        Connection velvetSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSundial");
        Statement velvetSundialStatement = null;
        ResultSet velvetSundialRows = null;
        try {
            velvetSundialStatement = velvetSundialConnection.createStatement();
            velvetSundialRows = velvetSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetSundialRows.getRow());
        } finally {
            if (velvetSundialRows != null) {
                velvetSundialRows.close();
            }
            if (velvetSundialStatement != null) {
                velvetSundialStatement.close();
            }
            velvetSundialConnection.close();
        }
    }
}
