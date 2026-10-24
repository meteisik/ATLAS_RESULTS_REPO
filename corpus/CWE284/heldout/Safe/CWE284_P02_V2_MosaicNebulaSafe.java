import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_MosaicNebulaSafe {
    private static boolean privateTrue = true;

    public void deleteMosaicNebulaAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (privateTrue) {
                data = System.getenv("MOSAIC_NEBULA_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection mosaicNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicNebula");
            try {
                PreparedStatement mosaicNebulaDelete = mosaicNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                mosaicNebulaDelete.setString(1, data);
                if (authorized) {
                    mosaicNebulaDelete.executeUpdate();
                } else {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                mosaicNebulaConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
