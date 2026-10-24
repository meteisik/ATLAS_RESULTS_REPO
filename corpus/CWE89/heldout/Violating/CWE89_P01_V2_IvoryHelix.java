import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_IvoryHelix {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runIvoryHelix() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("IVORY_HELIX_FILTER");
        } else {
            data = null;
        }
        Connection ivoryHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryHelix");
        Statement ivoryHelixStatement = null;
        ResultSet ivoryHelixRows = null;
        try {
            ivoryHelixStatement = ivoryHelixConnection.createStatement();
            ivoryHelixRows = ivoryHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryHelixRows.getRow());
        } finally {
            if (ivoryHelixRows != null) {
                ivoryHelixRows.close();
            }
            if (ivoryHelixStatement != null) {
                ivoryHelixStatement.close();
            }
            ivoryHelixConnection.close();
        }
    }
}
