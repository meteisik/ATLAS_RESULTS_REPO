import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetMantisSafe {

    public static String data;

    public void runVelvetMantis() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_VelvetMantisSafeSink()).queryVelvetMantis();
    }
}

class CWE89_P10_V1_VelvetMantisSafeSink {
    public void queryVelvetMantis() throws SQLException {
        String data = CWE89_P10_V1_VelvetMantisSafe.data;
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
