import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_IvoryHelix {

    private void queryIvoryHelix(String data) throws SQLException {
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

    public void runIvoryHelix() throws SQLException {
        String data;
        data = System.getenv("IVORY_HELIX_FILTER");
        queryIvoryHelix(data);
    }
}
