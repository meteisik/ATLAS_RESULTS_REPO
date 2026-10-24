import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetMantisSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runVelvetMantis() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = (new CWE89_P07_V2_VelvetMantisSafeSource()).loadVelvetMantis();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_VelvetMantisSafeSource {
    public String loadVelvetMantis() {
        String data;
        data = "foo";
        return data;
    }
}
