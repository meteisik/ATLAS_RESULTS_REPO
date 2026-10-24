import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_NovaAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String loadNovaAurora() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("NOVA_AURORA_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runNovaAurora() throws SQLException {
        String data = loadNovaAurora();
        Connection novaAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaAurora");
        Statement novaAuroraStatement = null;
        ResultSet novaAuroraRows = null;
        try {
            novaAuroraStatement = novaAuroraConnection.createStatement();
            novaAuroraRows = novaAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaAuroraRows.getRow());
        } finally {
            if (novaAuroraRows != null) {
                novaAuroraRows.close();
            }
            if (novaAuroraStatement != null) {
                novaAuroraStatement.close();
            }
            novaAuroraConnection.close();
        }
    }
}
