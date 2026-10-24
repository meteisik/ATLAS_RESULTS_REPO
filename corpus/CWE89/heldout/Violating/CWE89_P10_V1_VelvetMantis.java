import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetMantis {

    public static String data;

    public void runVelvetMantis() throws SQLException {
        data = System.getenv("VELVET_MANTIS_FILTER");
        (new CWE89_P10_V1_VelvetMantisSink()).queryVelvetMantis();
    }
}

class CWE89_P10_V1_VelvetMantisSink {
    public void queryVelvetMantis() throws SQLException {
        String data = CWE89_P10_V1_VelvetMantis.data;
        Connection velvetMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetMantis");
        Statement velvetMantisStatement = null;
        ResultSet velvetMantisRows = null;
        try {
            velvetMantisStatement = velvetMantisConnection.createStatement();
            velvetMantisRows = velvetMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetMantisRows.getRow());
        } finally {
            if (velvetMantisRows != null) {
                velvetMantisRows.close();
            }
            if (velvetMantisStatement != null) {
                velvetMantisStatement.close();
            }
            velvetMantisConnection.close();
        }
    }
}
