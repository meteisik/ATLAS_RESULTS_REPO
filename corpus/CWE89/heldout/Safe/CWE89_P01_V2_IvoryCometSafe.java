import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_IvoryCometSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runIvoryComet() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        Connection ivoryCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryComet");
        Statement ivoryCometStatement = null;
        ResultSet ivoryCometRows = null;
        try {
            ivoryCometStatement = ivoryCometConnection.createStatement();
            ivoryCometRows = ivoryCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryCometRows.getRow());
        } finally {
            if (ivoryCometRows != null) {
                ivoryCometRows.close();
            }
            if (ivoryCometStatement != null) {
                ivoryCometStatement.close();
            }
            ivoryCometConnection.close();
        }
    }
}
