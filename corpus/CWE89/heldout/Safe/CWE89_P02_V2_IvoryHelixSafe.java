import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_IvoryHelixSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runIvoryHelix() throws SQLException {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
